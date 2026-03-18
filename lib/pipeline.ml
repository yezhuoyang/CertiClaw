(** {1 Pipeline}

    {b [SUPPORT]} — Composes the core checker with rendering into a
    single structured result.  Both accepted and rejected paths
    preserve full context for audit / debugging.

    This module does NOT execute anything.  It is a pure function
    from (action, proof, policy) to {!Types.pipeline_result}. *)

open Types

(** [run ~policy ~proof ~dry_run action] runs the check-and-render
    pipeline.  Returns [PipelineAccepted plan] or
    [PipelineRejected (error, context)].

    On rejection, the context includes the action, inferred effects,
    and claimed effects — everything needed for an audit record. *)
let run ~(policy : policy) ~(proof : proof) ?(dry_run = true)
    (action : action) : pipeline_result =
  let inferred = Infer.infer_effects action in
  match Check.check ~policy ~proof ~action with
  | Rejected err ->
    PipelineRejected (err, {
      rejected_action  = action;
      inferred_effects = inferred;
      claimed_effects  = proof.claimed_effects;
    })
  | Accepted ->
    let rendered = Render.render action in
    PipelineAccepted {
      input_action     = action;
      inferred_effects = inferred;
      rendered;
      dry_run;
    }
