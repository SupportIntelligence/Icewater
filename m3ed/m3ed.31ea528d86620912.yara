
rule m3ed_31ea528d86620912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31ea528d86620912"
     cluster="m3ed.31ea528d86620912"
     cluster_size="92"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['0430e159f4268d17171ad7f69d2a32ae','0c2b5836bf67f70297af5678004a2334','a66f8c9dc4a9c14fd7ecd8a79141ab98']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0d8cdb0010d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
