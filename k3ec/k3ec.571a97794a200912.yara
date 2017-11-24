
rule k3ec_571a97794a200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.571a97794a200912"
     cluster="k3ec.571a97794a200912"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virtob malicious virut"
     md5_hashes="['3578da01d907e8337bcd14cfe754f7b3','4d916424dc373e8b6d8cf652120e8650','fd5b88b7e935b57fa2c296d237226769']"

   strings:
      $hex_string = { f90974068b46248945088d41ff83f8090f877a040000ff2485465800018b5d0c85db74548bc783e04233c90bc174495151536a0ae812edffff85c0751bff1564 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
