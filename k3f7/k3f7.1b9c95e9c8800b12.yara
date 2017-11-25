
rule k3f7_1b9c95e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.1b9c95e9c8800b12"
     cluster="k3f7.1b9c95e9c8800b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery redirector script"
     md5_hashes="['31d54f00103df9444b9d99245727a806','819154abe51710797b3f98e4d25faf63','e9fe0dd3235fa1ed678870be9c930ae0']"

   strings:
      $hex_string = { 333239372e61662d717569726b734d6f64657b6f766572666c6f772d783a68696464656e3b7d0a2361662d666f726d2d323035343433333239377b6261636b67 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
