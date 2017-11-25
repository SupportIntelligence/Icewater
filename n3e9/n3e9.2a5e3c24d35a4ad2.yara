
rule n3e9_2a5e3c24d35a4ad2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2a5e3c24d35a4ad2"
     cluster="n3e9.2a5e3c24d35a4ad2"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="multiplug mplug malicious"
     md5_hashes="['02c46f08297a3118303d347783ee4e44','04b845c659a671bf19119b2f743d876d','b7e4745512df746d0359b57ccb6d5057']"

   strings:
      $hex_string = { f03057328a32a432c0324433b7332f34613470348e34e834ab35d435dd353036393610371c37473704380d38ff380839f4393e3a473a6f3ac23ad63a1d3b163c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
