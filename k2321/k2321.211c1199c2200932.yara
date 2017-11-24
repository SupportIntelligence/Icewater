
rule k2321_211c1199c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211c1199c2200932"
     cluster="k2321.211c1199c2200932"
     cluster_size="22"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms hacktool kmsactivator"
     md5_hashes="['01b433c5dfa47c3aab7350d04fb72c9d','0286e1238f84fdf60f121e076d726ced','826a24cb4b906e1709db25cfae9cc403']"

   strings:
      $hex_string = { 64ecf8ad217dd2c590b240a896331923e9444a9856bd06e27a27462acceacea9cd1fbe38a24dc1415e5c5d0e4208afd0d682867571a358693d375f99de73bf0d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
