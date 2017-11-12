
rule m3e9_5b54e3899a430b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5b54e3899a430b16"
     cluster="m3e9.5b54e3899a430b16"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer fixflo"
     md5_hashes="['094ade4f803e285c7548d9facc524d6b','0b959820c23b03b6cefe5b0ac12488cd','c46cb5ed01d780aa6ad46876021b9eef']"

   strings:
      $hex_string = { a904d3cbdf8f35d06cdf6e2d4a007b027342ecdb5d9fb1707bb69772e8f0bdc1ce57454ee5f54ce4900ef5368d313daf970091c7922b88726005bf274e1c05d1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
