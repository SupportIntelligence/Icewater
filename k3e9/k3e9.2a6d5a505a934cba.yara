
rule k3e9_2a6d5a505a934cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2a6d5a505a934cba"
     cluster="k3e9.2a6d5a505a934cba"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['182fd226fea5f68932afc78965010e5f','3b9cc8e486711c4f28301bde88fa98ad','e5a1833454a3e68473d7f70d46aacf28']"

   strings:
      $hex_string = { b629c08f49b72779f6daf191379e7826afa083c582b0624306c9dbbfe3875d086ef01c52fefd3e01f7fc0d95d088489d32efd5b14a049723d803c271794ce756 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
