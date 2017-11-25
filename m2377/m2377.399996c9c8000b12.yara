
rule m2377_399996c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.399996c9c8000b12"
     cluster="m2377.399996c9c8000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['72634fdfc0bee825f8e32564bf35b479','9a1ccfa21911f1819f7fdd2a33319ff3','fbd5cfd841adab16dc4a4c06f5a56764']"

   strings:
      $hex_string = { 743e0a3c6c696e6b20687265663d27687474703a2f2f332e62702e626c6f6773706f742e636f6d2f2d3465784f725f5136415a512f555f6a79774a48414d4b49 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
