
rule n3f7_691c929dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.691c929dc6220b32"
     cluster="n3f7.691c929dc6220b32"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['42c3c25323148723d80c4a34fe3c46f1','644136cdab9bd7fba175b309e299a186','f8fe07a21192665fb7b110b702fb79f0']"

   strings:
      $hex_string = { 4e5448524f313336535031315f56564f5f43414d32375f3030382e6a70673c2f613e0a3c2f6c693e0a3c6c693e0a3c61206469723d276c74722720687265663d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
