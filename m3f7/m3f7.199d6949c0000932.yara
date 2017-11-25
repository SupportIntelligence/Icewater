
rule m3f7_199d6949c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.199d6949c0000932"
     cluster="m3f7.199d6949c0000932"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0ff8ccb2b64551782dd448613314b7ce','12c4e9af34bd1987cf2cc4ed687b27ab','b371bbe77d075f0a8fd3ed02be6f7599']"

   strings:
      $hex_string = { 414143592f467551532d643768784d512f533232302d7338302f6469615f6d69727a615f6c617267652e6a7067272077696474683d273731272f3e0a3c2f613e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
