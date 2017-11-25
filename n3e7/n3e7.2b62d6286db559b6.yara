
rule n3e7_2b62d6286db559b6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.2b62d6286db559b6"
     cluster="n3e7.2b62d6286db559b6"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr dlboost malicious"
     md5_hashes="['04088b634ebdb3bea1b437fefbbb927e','0c45c10cb26c870e852392a3d23cc872','04088b634ebdb3bea1b437fefbbb927e']"

   strings:
      $hex_string = { 639dd55ac2dd5c5f5ede2a20ac29594b941c0f2f55b19fedc692e6795248e109f8b422f378ec34caae24c9717ed30dcfbe9c03af67fdadd8f27f8ec35b72d4b2 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
