
rule o2321_5132088cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.5132088cea210912"
     cluster="o2321.5132088cea210912"
     cluster_size="85"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr unwanted"
     md5_hashes="['01380a0732cfdf1a045b041d93c7f39b','04ba0bc2d999b073aa5af7a1b325213d','474bc7988d47722f7fbcd28edb94abc8']"

   strings:
      $hex_string = { 8d77298033256ff4e832eaab171310c04a2099bd5778dc918cd3ca4d952d656d8b5a9ebb1d38a80302275eb5533b4637db399a2ca959f66771f2b4343eebd0af }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
