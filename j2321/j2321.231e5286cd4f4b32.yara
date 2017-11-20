
rule j2321_231e5286cd4f4b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.231e5286cd4f4b32"
     cluster="j2321.231e5286cd4f4b32"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd trojandownloader"
     md5_hashes="['4c66ddb2e1a1fc3816791fb065b17395','958bef9f1d1f7c60352955e99f858300','dc9cf38a7fa9ed00c6ae8e3b2a7a45cb']"

   strings:
      $hex_string = { 2c6a580311f72390ccfc495fb5af951a3ed0c72bca6b5f33d7ed842567511efe5c050d173abeae4bd9e9a49e20f550561261c94378c9c237d664997a8863799d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
