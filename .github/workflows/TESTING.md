# Testing Github Action workflows

It's possible to test the Github Action workflows locally by using https://github.com/nektos/act

You can start by listing all available jobs in our workflows:

```bash
act -l
```

We have prepared examples on how to test some types of triggers in the `docker.yml` workflow, but it shouldn't be hard to adapt these examples to test other combinations of jobs and triggers.

## Testing a Tag Push

To simulate the workflow being trigger by the push of a tag, first generate an event file like this:

```bash
cat <<EOF > event.json
{
  "ref": "refs/tags/v0.53.0-rc.1"
}
EOF
```

You can change the tag in this event to simulate different types of tags.

Then, run the `buildx` job with a `push` event providing the event context and a secret called `DOCKERHUB_IMAGE`:

```bash
act push -e event.json -j buildx -s DOCKERHUB_IMAGE=testing_locally
```

## Testing a Scheduled run

Simulating a scheduled run is similar, just change the type of event:

```bash
act schedule -j buildx -s DOCKERHUB_IMAGE=testing_locally
```