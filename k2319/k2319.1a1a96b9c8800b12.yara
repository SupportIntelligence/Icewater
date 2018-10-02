
rule k2319_1a1a96b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1a96b9c8800b12"
     cluster="k2319.1a1a96b9c8800b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d8263a90ea09e03fefa5b142de78c2f72f1da465','31e1e0cf71acb0af42a353b8b92bc959765f31eb','1f73eaa0b3829503d77e57692e25cc8dd22dd66b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1a96b9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20705b725d3b7d76617220503d28307846423e3d28352e36303045322c3835293f28307842372c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
