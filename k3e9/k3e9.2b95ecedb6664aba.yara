
rule k3e9_2b95ecedb6664aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b95ecedb6664aba"
     cluster="k3e9.2b95ecedb6664aba"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['1003a34bb6806059968cad0e82cfbfdd','1ab01fabafc69bd6e597f3696d5109a5','c22da3ed4d40ade1795188fe8031e00e']"

   strings:
      $hex_string = { 7661e2d05f72b4ac291397473a0e99aee7bf50a8c514c93093276ac1f779da1cad58cd48b6b717326b2f64fe0f0a6de567464c21ac05081da3867c4bd1334fcb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
