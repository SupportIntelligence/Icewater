
rule k2321_31912d0b99bbd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.31912d0b99bbd932"
     cluster="k2321.31912d0b99bbd932"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['014dc6f5cb4dfbb154c019f7b04ce07c','4693692f27569d04b4db8ed3d90febbd','f38a8391fa56185c095fa6f331c19678']"

   strings:
      $hex_string = { d868c3bc86221b6bd951ab2d960a67d2cb75337a7bb1a12f09e9ad8000ff0130250da746e4568ac88d4eae14cc10a98ab6dc623eb7026431ba923b0aea17f8df }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
