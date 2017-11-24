
rule m2319_1b196a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1b196a49c0000b12"
     cluster="m2319.1b196a49c0000b12"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['0722a88a14047ccfc72d9444704c8028','69a92345129d43154e9b442fe7442596','e619051182faa7cc7ff620a2b7e54737']"

   strings:
      $hex_string = { 6d656e74427949642827636c69636b6a61636b2d627574746f6e2d777261707065722d3627292e7374796c652e6865696768743d202232307078223b0a09090a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
