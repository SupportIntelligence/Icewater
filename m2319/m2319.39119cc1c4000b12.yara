
rule m2319_39119cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.39119cc1c4000b12"
     cluster="m2319.39119cc1c4000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['38716b1814cdff4359529fdeab9d28d1','d2146e8a13a2cf12fb420ea17b94fc06','fb0d1854d93b7a8ed51ba4d9fdbceaaf']"

   strings:
      $hex_string = { 743e0a3c6c696e6b20687265663d27687474703a2f2f332e62702e626c6f6773706f742e636f6d2f2d3465784f725f5136415a512f555f6a79774a48414d4b49 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
