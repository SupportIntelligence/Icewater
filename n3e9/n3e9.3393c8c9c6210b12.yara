
rule n3e9_3393c8c9c6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3393c8c9c6210b12"
     cluster="n3e9.3393c8c9c6210b12"
     cluster_size="44"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nymaim bbzi malicious"
     md5_hashes="['01622c47fb976e1091934ac7c9d1e3ea','13456a6a70a635308cbd9b95f000450f','67a9161b7a50939b1848200cc8e538b6']"

   strings:
      $hex_string = { 910ff36c423db2386e8983ac54e54f6784039c3f2fb41d8dd9732d20d304f6f0a3743e7f2c05da17857c224b6633a22a188cb61cf52b478a9f8776411152f9ff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
