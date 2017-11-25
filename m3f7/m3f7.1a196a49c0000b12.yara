
rule m3f7_1a196a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.1a196a49c0000b12"
     cluster="m3f7.1a196a49c0000b12"
     cluster_size="10"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['3212402c1f840f92514cf7674e6b8603','58846779329dcab133296ccc9b977131','fea855e1ee22e08e935a8d25b13192b5']"

   strings:
      $hex_string = { 6d656e74427949642827636c69636b6a61636b2d627574746f6e2d777261707065722d3627292e7374796c652e6865696768743d202232307078223b0a09090a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
