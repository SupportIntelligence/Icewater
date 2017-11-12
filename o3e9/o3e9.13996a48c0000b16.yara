
rule o3e9_13996a48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.13996a48c0000b16"
     cluster="o3e9.13996a48c0000b16"
     cluster_size="471"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor ocna riskware"
     md5_hashes="['01466aeb0c9b1600ba8dedbd352e5f7c','022003a1455cc23f3ea5881b85166980','0a55a4be0ecffd680ba2193196cc4e79']"

   strings:
      $hex_string = { 301406082b0601050507030206082b0601050507030330290603551d1104223020a41e301c311a301806035504031311566572695369676e4d504b492d322d31 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
