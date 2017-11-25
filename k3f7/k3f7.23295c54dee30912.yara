
rule k3f7_23295c54dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.23295c54dee30912"
     cluster="k3f7.23295c54dee30912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['3c5409b7f0e45dfc1a1561d952e0a1b7','91dbdeff434a04db418b09e9441da5f3','9871f264d7dec699eb8293182216bbf2']"

   strings:
      $hex_string = { 41414143672f58534535434d5f486b65672f7337322d632f656d6d61776174736f6e7570736b6972745f3034313930385f313874686269727468646179706172 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
