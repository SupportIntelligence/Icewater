
rule n2321_331a95b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.331a95b9c2200b12"
     cluster="n2321.331a95b9c2200b12"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="solimba bundler morstar"
     md5_hashes="['05cd637d54ef8e90b648ab59c413e5eb','0ad3e196162d4c9bf896f87c1931a9d0','f1d1bd119991740a5fa49ed8318d8c1f']"

   strings:
      $hex_string = { acb376a57bdc25a4f89fe9f744b8213105ca3bbda71d04a8d50dfede8e70cc43c57e6e992b9b97df4b2219ebdd72fd655080f60a00d7c101d386a1886afcae10 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
