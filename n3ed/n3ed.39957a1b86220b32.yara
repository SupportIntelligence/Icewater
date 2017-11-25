
rule n3ed_39957a1b86220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39957a1b86220b32"
     cluster="n3ed.39957a1b86220b32"
     cluster_size="79"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['01593eecda7d2bbf711b92ab8f067f03','0b31a8aa9b21b5b05977c552403ec39a','a0d287d54d47a210cf494015b72136cb']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0dbc7f0510d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
