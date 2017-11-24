
rule k3e9_2b9554bcd99bd916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b9554bcd99bd916"
     cluster="k3e9.2b9554bcd99bd916"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cossta farfli"
     md5_hashes="['10c0a6b15a6d1903541cde3fa7bcf37a','296729b1f3aac178ffe2ec002e484014','f1999c01d6cbddbbad55f3bbc3c792ff']"

   strings:
      $hex_string = { 1a59b13a814f13f2f1cefa1b17df833435bd516068886620a32937022cbe7e4ecedac1bbd2f873f0041fc607bd32ca1cb57142e9b9b391229f10f53cb461d8a1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
