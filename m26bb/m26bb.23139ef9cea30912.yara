
rule m26bb_23139ef9cea30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.23139ef9cea30912"
     cluster="m26bb.23139ef9cea30912"
     cluster_size="2361"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mailru malicious unwanted"
     md5_hashes="['3e69d24126a24b8515e4f129a49015d4e44f5004','ee9bd5c66a036e9eb5693c591a14270b68b5cc9f','ce69a42adc9035b02a02e72e32e6490cb4d9cd5e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.23139ef9cea30912"

   strings:
      $hex_string = { 6808e941005056e80d21000083c40c85c075768d4e02397d147403c606458b55188b420c803830742d8b52044a7906f7dac646012d6a645b3bd37c088bc299f7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
