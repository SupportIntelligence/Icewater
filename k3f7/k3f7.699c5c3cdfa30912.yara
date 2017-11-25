
rule k3f7_699c5c3cdfa30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.699c5c3cdfa30912"
     cluster="k3f7.699c5c3cdfa30912"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['0d5ee482763b53b40d06914c83794fa3','aed13bb3053a73472fd565f2fcad9154','ff49a33d2c690eb14daff3a5a71cc2cf']"

   strings:
      $hex_string = { 2e66616365626f6f6b2e6e65742f69745f49542f616c6c2e6a73237866626d6c3d312661707049643d323132353435393938393031303131223b0a2020666a73 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
