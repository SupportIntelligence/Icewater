
rule k3e9_0ab24d36dabb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0ab24d36dabb1912"
     cluster="k3e9.0ab24d36dabb1912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious genmalicious"
     md5_hashes="['04bacc50e8e78dc946f2d2a6080dd236','2a085f05273d637d8c5f51e61e8fd268','860e21698099b6ced257d193ea03de74']"

   strings:
      $hex_string = { 5bd05061e10365f65fc9f8cdc3f0052ebda08d1304accb6da5e4867a741a266e3523089918a80e77426c4d153e3ce10ac42ab7f156fa11751f8fb6cfb0cac292 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
