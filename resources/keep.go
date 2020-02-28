package resources

// Include is a dummy method which will be imported by 'insights' package.
// The effect is that the 'resources' folder will be available under the
// 'vendor' folder when running 'go mod vendor' on an application that imports
// the Security Overview package
func Include() {}
