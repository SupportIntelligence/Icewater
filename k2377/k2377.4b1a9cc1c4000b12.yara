
rule k2377_4b1a9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4b1a9cc1c4000b12"
     cluster="k2377.4b1a9cc1c4000b12"
     cluster_size="10"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['05ec2469ff039d4ab8bdac2e12bc46c0','1ebb414387a948b79392dead3ea7fcfe','c3f1bc7ae147982e4f97b9515fd00c0f']"

   strings:
      $hex_string = { 222c31303030293b0a7d20293b0a66756e6374696f6e20636c69636b6a61636b5f686964657228297b0a6a51756572792822696e70757422292e6d6f7573656f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
