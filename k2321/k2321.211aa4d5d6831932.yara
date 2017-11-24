
rule k2321_211aa4d5d6831932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211aa4d5d6831932"
     cluster="k2321.211aa4d5d6831932"
     cluster_size="79"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok eyvjjib fmmfr"
     md5_hashes="['00939e2c2a974afdb0ab07d9b50a7d8f','05096053e7391852bc215626b72d4673','31b24cf799507ba42d2dd0c97ad1a045']"

   strings:
      $hex_string = { 765934562dfbc86b44757db1b3eed70bf2a53b7abdf6d43a6d4b14e553ca0f7f2769884be88655cf1b45eb2b49f5b2f08316225452afa6dc98e23f219504e702 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
