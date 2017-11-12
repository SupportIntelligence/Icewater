
rule n3ed_31a440cba6221132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a440cba6221132"
     cluster="n3ed.31a440cba6221132"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['3b20efbf82954ea46827b19858587aa9','a6fbd1ab882eebe5f720c337a3299032','c6482f7466679fcae3091c15161765d3']"

   strings:
      $hex_string = { 1100ff08b001eb232bc203c02bf23bc67d178d0c510fb714410fb75c4102c1e2100bd340891740ebb632c05f5e5b5dc38a4424048ac880e96180f919770204e0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
