
rule n3e9_239a5bb9d4e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.239a5bb9d4e30912"
     cluster="n3e9.239a5bb9d4e30912"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler optimuminstaller"
     md5_hashes="['106fc984030785066329ec9236a01d08','2e9a2436b90b43e30127ce75db819417','6bca3457b4e9fef1b73d7db789e3631d']"

   strings:
      $hex_string = { 8054827c9929c958a2a124e3f8f41ab665c7be91ddb230275e6aa60c6b579e45acae6df21e95ab8a76b220668d281acfda5cf6878f40df53d91702514be73ed7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
