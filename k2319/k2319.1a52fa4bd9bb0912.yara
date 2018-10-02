
rule k2319_1a52fa4bd9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a52fa4bd9bb0912"
     cluster="k2319.1a52fa4bd9bb0912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['2446a166afe12f382de3526f0424779e7adc4369','afe91554990eec99c7230dd6278a93217f8fc807','fb22808d7298c79206c32225278f2e6ec92cef3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a52fa4bd9bb0912"

   strings:
      $hex_string = { 4f297b72657475726e20713c4f3b7d2c27543977273a66756e6374696f6e28297b6170705b2822616d222b2835332e3245313e3d28382e33373045322c39293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
