package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Wessie/appdirs"
	"github.com/andrewbaxter/dinker/dinkerlib"
	imagecopy "github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/oci/archive"
	ocidir "github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/transports/alltransports"
	imagetypes "github.com/containers/image/v5/types"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/samber/lo"
)

// Provider
type ThisProviderModel struct {
	CacheDir types.String `tfsdk:"cache_dir"`
}

type ThisProvider struct {
}

func (ThisProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config ThisProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.ResourceData = config
}

func (ThisProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}

func (ThisProvider) Metadata(_ context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "dinker"
}

func (ThisProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource {
			return &ImageResource{}
		},
	}
}

func (ThisProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = providerschema.Schema{
		MarkdownDescription: "Build and store an OCI image",
		Attributes: map[string]providerschema.Attribute{
			"cache_dir": providerschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Cache intermediate build files (namely FROM images)",
			},
		},
	}
}

// Resource
type ImageResourceModelFile struct {
	Source types.String `tfsdk:"source"`
	Dest   types.String `tfsdk:"dest"`
	Mode   types.String `tfsdk:"mode"`
}

type ImageResourceModelPort struct {
	Port      types.Int64  `tfsdk:"port"`
	Transport types.String `tfsdk:"transport"`
}

type ImageResourceModel struct {
	// Required
	Dest  types.String             `tfsdk:"dest"`
	Files []ImageResourceModelFile `tfsdk:"files"`
	// Required if no FROM
	Arch types.String `tfsdk:"arch"`
	Os   types.String `tfsdk:"os"`
	// Optional
	From         types.String             `tfsdk:"from"`
	FromUser     types.String             `tfsdk:"from_user"`
	FromPassword types.String             `tfsdk:"from_password"`
	FromHttp     types.Bool               `tfsdk:"from_http"`
	DestUser     types.String             `tfsdk:"dest_user"`
	DestPassword types.String             `tfsdk:"dest_password"`
	DestHttp     types.Bool               `tfsdk:"dest_http"`
	AddEnv       map[string]types.String  `tfsdk:"add_env"`
	ClearEnv     types.Bool               `tfsdk:"clear_env"`
	WorkingDir   types.String             `tfsdk:"working_dir"`
	User         types.String             `tfsdk:"user"`
	Entrypoint   []types.String           `tfsdk:"entrypoint"`
	Cmd          []types.String           `tfsdk:"cmd"`
	Ports        []ImageResourceModelPort `tfsdk:"ports"`
	Labels       map[string]types.String  `tfsdk:"labels"`
	StopSignal   types.String             `tfsdk:"stop_signal"`
	// Outputs
	RenderedDest types.String `tfsdk:"rendered_dest"`
	Hash         types.String `tfsdk:"hash"`
}

type ImageResource struct {
	ProviderData ThisProviderModel
}

var (
	_ resource.Resource              = &ImageResource{}
	_ resource.ResourceWithConfigure = &ImageResource{}
)

func (ImageResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_image"
}

func (ImageResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resourceschema.Schema{
		MarkdownDescription: "Build and push an image",
		Attributes: map[string]resourceschema.Attribute{
			// Required
			"dest": resourceschema.StringAttribute{
				MarkdownDescription: "Where to send generated image; skopeo-style reference, see <https://github.com/containers/image/blob/main/docs/containers-transports.5.md> for a full list. This is a pattern - you can add the following strings which will be replaced with generated information:\n\n* `{hash}` - A sha256 sum of all the information used to generate the image (note: this should be stable but has no formal specification and is unrelated to the pushed manifest hash).\n\n* `{short_hash}` - The first hex digits of the hash",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"files": resourceschema.ListNestedAttribute{
				MarkdownDescription: "Files to add to image",
				Required:            true,
				NestedObject: resourceschema.NestedAttributeObject{
					Attributes: map[string]resourceschema.Attribute{
						"source": resourceschema.StringAttribute{
							MarkdownDescription: "Local file to include in image",
							Required:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
						"dest": resourceschema.StringAttribute{
							MarkdownDescription: "Where to place the file in the image; defaults to filename of source in image root",
							Optional:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
						"mode": resourceschema.StringAttribute{
							MarkdownDescription: "File mode in octal, defaults to 0644",
							Optional:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
					},
				},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},

			// Required if no FROM
			"arch": resourceschema.ListAttribute{
				MarkdownDescription: "Defaults to `from` image architecture. Required if `from` omitted.",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"os": resourceschema.ListAttribute{
				MarkdownDescription: "Defaults to `from` image os. Required if `from` omitted.",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},

			// Optional
			"from": resourceschema.StringAttribute{
				MarkdownDescription: "FROM image to base generated image on; skopeo-style reference, see <https://github.com/containers/image/blob/main/docs/containers-transports.5.md> for a full list. If not specified, has no base layer.",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"from_user": resourceschema.StringAttribute{
				MarkdownDescription: "User to use if pulling FROM image from remote",
				Optional:            true,
			},
			"from_password": resourceschema.StringAttribute{
				MarkdownDescription: "Password to use if pulling FROM image from remote",
				Optional:            true,
			},
			"from_http": resourceschema.BoolAttribute{
				MarkdownDescription: "Allow http and unverified SSL",
				Optional:            true,
			},
			"dest_user": resourceschema.StringAttribute{
				MarkdownDescription: "User to use if pushing generated image to remote",
				Optional:            true,
			},
			"dest_password": resourceschema.StringAttribute{
				MarkdownDescription: "Password to use if pushing generated image to remote",
				Optional:            true,
			},
			"dest_http": resourceschema.BoolAttribute{
				MarkdownDescription: "Allow http and unverified SSL",
				Optional:            true,
			},
			"add_env": resourceschema.MapAttribute{
				MarkdownDescription: "Add these environment variables when running command in container",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
			"clear_env": resourceschema.BoolAttribute{
				MarkdownDescription: "User to use if pushing generated image to remote",
				Optional:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"working_dir": resourceschema.StringAttribute{
				MarkdownDescription: "Working dir for command in container; defaults to working dir in FROM image",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"user": resourceschema.StringAttribute{
				MarkdownDescription: "User to run command as in container; defaults to user in FROM image",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"entrypoint": resourceschema.ListAttribute{
				MarkdownDescription: "Un-overridable command parts, concatenated before `cmd`",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"cmd": resourceschema.ListAttribute{
				MarkdownDescription: "Overridable command parts, concatenated after `entrypoint`",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"ports": resourceschema.ListNestedAttribute{
				MarkdownDescription: "Container ports to expose",
				Optional:            true,
				NestedObject: resourceschema.NestedAttributeObject{
					Attributes: map[string]resourceschema.Attribute{
						"port": resourceschema.Int64Attribute{
							MarkdownDescription: "Internal port to make available",
							Required:            true,
							PlanModifiers: []planmodifier.Int64{
								int64planmodifier.RequiresReplace(),
							},
						},
						"transport": resourceschema.StringAttribute{
							MarkdownDescription: "Port protocol (`tcp`), defaults to `tcp`",
							Optional:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
					},
				},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"labels": resourceschema.MapAttribute{
				MarkdownDescription: "Metadata to attach to image",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
				},
			},
			"stop_signal": resourceschema.StringAttribute{
				MarkdownDescription: "Signal to use to stop command in container when shutting down",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			// Outputs
			"rendered_dest": resourceschema.StringAttribute{
				MarkdownDescription: "`dest` after interpolating generated information.",
				Computed:            true,
			},
			"hash": resourceschema.StringAttribute{
				MarkdownDescription: "Addressable content hash of the pushed image manifest in a format `algo:hex` like `sha256:0123abcd...`",
				Computed:            true,
			},
		},
	}
}

func (i *ImageResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	// Sometimes called before provider configured?
	if req.ProviderData == nil {
		return
	}
	i.ProviderData = req.ProviderData.(ThisProviderModel)
}

func buildDestImageCtx(state *ImageResourceModel) imagetypes.SystemContext {
	return imagetypes.SystemContext{
		DockerAuthConfig: &imagetypes.DockerAuthConfig{
			Username: state.DestUser.ValueString(),
			Password: state.DestPassword.ValueString(),
		},
		OCIInsecureSkipTLSVerify:          state.DestHttp.ValueBool(),
		DockerInsecureSkipTLSVerify:       imagetypes.NewOptionalBool(state.DestHttp.ValueBool()),
		DockerDaemonInsecureSkipTLSVerify: state.DestHttp.ValueBool(),
	}
}

func (i *ImageResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ImageResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hash, err := func() (*string, error) {
		destRef, err := alltransports.ParseImageName(state.RenderedDest.ValueString())
		if err != nil {
			return nil, fmt.Errorf("invalid dest image ref %s: %w %#v", state.RenderedDest.ValueString(), err, err)
		}
		destImageCtx := buildDestImageCtx(&state)

		destRefSrc, err := destRef.NewImageSource(ctx, &destImageCtx)
		if err != nil {
			// Assume any error == not found. Returns a "manifest unknown" in local testing but I don't know
			// if that's host specific, etc
			return nil, nil
		}
		defer func() {
			if err := destRefSrc.Close(); err != nil {
				resp.Diagnostics.AddWarning("Failed to close dest image ref source", err.Error())
			}
		}()
		manifestRaw, _, err := destRefSrc.GetManifest(ctx, nil)
		if err != nil {
			// Assume any error == not found, since I didn't see a good way to extract 404 errors from this call
			return nil, nil
		}
		manifestDigest, err := manifest.Digest(manifestRaw)
		if err != nil {
			return nil, err
		}
		out := manifestDigest.String()
		return &out, nil
	}()
	if err != nil {
		resp.Diagnostics.AddError("Error reading image state", err.Error())
		return
	} else {
		if hash != nil {
			state.Hash = types.StringValue(*hash)
		} else {
			state.Hash = types.StringNull()
		}
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (i *ImageResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var state ImageResourceModel
	diags := req.Plan.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := func() error {
		// Prep
		var cachePath dinkerlib.AbsPath
		{
			cachePath0 := i.ProviderData.CacheDir.ValueString()
			if cachePath0 == "" {
				cachePath0 = appdirs.UserCacheDir("terraform-dinker", "", "", true)
			}
			cachePath1, err := filepath.Abs(cachePath0)
			if err != nil {
				return fmt.Errorf("invalid cache dir [%s]: %w", cachePath0, err)
			}
			cachePath = dinkerlib.AbsPath(cachePath1)
			if err := os.MkdirAll(cachePath.Raw(), 0o755); err != nil {
				return fmt.Errorf("error creating cache dir at %s: %w", cachePath, err)
			}
		}

		var policyContext *signature.PolicyContext
		{
			policy, err := signature.DefaultPolicy(nil)
			if err != nil {
				return fmt.Errorf("error setting up docker registry client policy context signature: %w", err)
			}
			policyContext, err = signature.NewPolicyContext(policy)
			if err != nil {
				return fmt.Errorf("error setting up docker registry client policy context: %w", err)
			}
		}

		// Ensure from image cached locally
		var imagePath dinkerlib.AbsPath
		{
			d := sha256.New()
			d.Write([]byte(state.From.ValueString()))
			imagePath = cachePath.Join(fmt.Sprintf(
				"%s-%s.tar",
				hex.EncodeToString(d.Sum([]byte{})),
				regexp.MustCompile("[^a-zA-Z_.-]+").ReplaceAllString(state.From.ValueString(), "_"),
			))
		}
		if !imagePath.Exists() {
			sourceRef, err := alltransports.ParseImageName(state.From.ValueString())
			if err != nil {
				return fmt.Errorf("error parsing FROM pull ref %s: %w", state.From, err)
			}
			imageRef, err := archive.Transport.ParseReference(imagePath.Raw())
			if err != nil {
				panic(err)
			}
			_, err = imagecopy.Image(
				context.TODO(),
				policyContext,
				imageRef,
				sourceRef,
				&imagecopy.Options{
					SourceCtx: &imagetypes.SystemContext{
						DockerAuthConfig: &imagetypes.DockerAuthConfig{
							Username: state.FromUser.ValueString(),
							Password: state.FromPassword.ValueString(),
						},
						OCIInsecureSkipTLSVerify:          state.FromHttp.ValueBool(),
						DockerInsecureSkipTLSVerify:       imagetypes.NewOptionalBool(state.FromHttp.ValueBool()),
						DockerDaemonInsecureSkipTLSVerify: state.FromHttp.ValueBool(),
					},
				},
			)
			if err != nil {
				return fmt.Errorf("error pulling FROM image %s: %w", state.From, err)
			}
		}

		// Build image
		{
			t, err := os.MkdirTemp("", ".dinker-image-*")
			if err != nil {
				return fmt.Errorf("unable to create temp file to write generated image to: %w", err)
			}
			t0, err := filepath.Abs(t)
			if err != nil {
				panic(err)
			}
			destDirPath := dinkerlib.AbsPath(t0)
			defer func() {
				if err := os.RemoveAll(destDirPath.Raw()); err != nil {
					resp.Diagnostics.AddWarning("Failed to clean up image staging dir "+destDirPath.String(), err.Error())
				}
			}()
			hash, err := dinkerlib.BuildImage(dinkerlib.BuildImageArgs{
				FromPath:    imagePath,
				DestDirPath: destDirPath,
				Files: lo.Map(
					state.Files,
					func(e ImageResourceModelFile, i int) dinkerlib.BuildImageArgsFile {
						return dinkerlib.BuildImageArgsFile{
							Source: dinkerlib.MakeAbsPath(e.Source.ValueString()),
							Dest:   e.Dest.ValueString(),
							Mode:   e.Mode.ValueString(),
						}
					},
				),
				Architecture: state.Arch.String(),
				Os:           state.Os.String(),
				ClearEnv:     state.ClearEnv.ValueBool(),
				AddEnv: lo.MapEntries(
					state.AddEnv,
					func(key string, value types.String) (string, string) {
						return key, value.ValueString()
					},
				),
				WorkingDir: state.WorkingDir.ValueString(),
				User:       state.User.ValueString(),
				Entrypoint: lo.Map(state.Entrypoint, func(item types.String, index int) string {
					return item.ValueString()
				}),
				Cmd: lo.Map(state.Cmd, func(item types.String, index int) string {
					return item.ValueString()
				}),
				Ports: lo.Map(
					state.Ports,
					func(item ImageResourceModelPort, index int) dinkerlib.BuildImageArgsPort {
						return dinkerlib.BuildImageArgsPort{
							Port:      int(item.Port.ValueInt64()),
							Transport: item.Transport.ValueString(),
						}
					},
				),
				Labels: lo.MapEntries(
					state.Labels,
					func(key string, value types.String) (string, string) {
						return key, value.ValueString()
					},
				),
				StopSignal: state.StopSignal.ValueString(),
			})
			if err != nil {
				return fmt.Errorf("error building image: %w", err)
			}

			// Push image
			{
				sourceRef, err := ocidir.Transport.ParseReference(destDirPath.Raw())
				if err != nil {
					panic(err)
				}

				destString := state.Dest.ValueString()
				for k, v := range map[string]string{
					"hash":       hash,
					"short_hash": hash[:8],
				} {
					destString = strings.ReplaceAll(destString, fmt.Sprintf("{%s}", k), v)
				}
				state.RenderedDest = types.StringValue(destString)
				destRef, err := alltransports.ParseImageName(destString)
				if err != nil {
					return fmt.Errorf("invalid dest image ref %s: %w %#v", destString, err, err)
				}

				destImageCtx := buildDestImageCtx(&state)
				destImage, err := destRef.NewImageDestination(context.TODO(), &destImageCtx)
				if err != nil {
					panic(err)
				}
				manifestFormat := ""
				for _, format := range destImage.SupportedManifestMIMETypes() {
					// Prefer docker manifest
					if format == manifest.DockerV2Schema2MediaType {
						manifestFormat = format
					}
				}
				manifestRaw, err := imagecopy.Image(
					context.TODO(),
					policyContext,
					destRef,
					sourceRef,
					&imagecopy.Options{
						DestinationCtx:        &destImageCtx,
						ForceManifestMIMEType: manifestFormat,
					},
				)
				if err != nil {
					return fmt.Errorf("error uploading image: %w", err)
				}

				manifestDigest, err := manifest.Digest(manifestRaw)
				if err != nil {
					return err
				}
				state.Hash = types.StringValue(manifestDigest.String())
			}
		}

		return nil
	}(); err != nil {
		resp.Diagnostics.AddError("Error building and pushing image", err.Error())
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (ImageResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	// nop
}

func (ImageResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	panic("ASSERTION! dead code")
}

// Main
func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(
		context.Background(),
		func() provider.Provider {
			return ThisProvider{}
		},
		providerserver.ServeOpts{
			Address: "registry.terraform.io/andrewbaxter/dinker",
			Debug:   debug,
		},
	)

	if err != nil {
		log.Fatal(err.Error())
	}
}
