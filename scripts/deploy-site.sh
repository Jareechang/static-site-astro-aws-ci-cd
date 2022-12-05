echo "Step 1: Install & Build"

pnpm install --production
pnpm run build --filter "@site/*"

echo "Step 2: Syncing to s3"
aws s3 sync $PWD/site/dist s3://$AWS_S3_BUCKET_NAME
