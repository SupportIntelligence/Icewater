
rule m3ed_31ea6a09c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31ea6a09c0000912"
     cluster="m3ed.31ea6a09c0000912"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit cosmu nimnul"
     md5_hashes="['04511d322f1985232f76fcd321e44cb3','394b0a7b504717af5f52eee9480766e7','e8d7c2cc6f84f7cd8bee41d58abcd5dc']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0d8cdb0010d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
