
rule n3ed_39957a0dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39957a0dc6620b32"
     cluster="n3ed.39957a0dc6620b32"
     cluster_size="614"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['01bbddc79d29495571d45e9127ebcf0d','02afa4b5f56980387f4e0257b92d9658','11ca8fb8e6394a16b5a9d8172eb0d1d1']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0dbc7f0510d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
