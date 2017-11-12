
rule n3e9_39c215e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c215e9c8800b12"
     cluster="n3e9.39c215e9c8800b12"
     cluster_size="371"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy trojandropper backdoor"
     md5_hashes="['0227defcde062e3454357b0ceac82c01','07c2d17436099ee81f695878d4dc7f12','34b146a1c74b7c904fa06a7598458db1']"

   strings:
      $hex_string = { 3f4c3f5e3f703f823f943fa63fe03f000000c00100440000005d32c632d732fd340e352e3557356b357f35eb352736ac36ed361037be38fb38b539be39003a09 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
