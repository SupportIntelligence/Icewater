
rule k3e9_092469e1dec34916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.092469e1dec34916"
     cluster="k3e9.092469e1dec34916"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted playturtle"
     md5_hashes="['1359c631e3012f35d126ab24a1acf050','17066b3248dd2dcc5be2ee0505bda180','ee8db38b0cf6f9618c62b5a641d1a066']"

   strings:
      $hex_string = { c8131231f7d98c35b6bd0a3b43267a23f02b5911a9d25b7044575a4d91c56acf94c4eefbb84cdf828faf99c36c970c09d2657f03a7b0586bcb793374a541f9da }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
