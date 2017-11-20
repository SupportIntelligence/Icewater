
rule k2321_2b95ecedb6664aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b95ecedb6664aba"
     cluster="k2321.2b95ecedb6664aba"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['05dd77ec2cd1c0e9dde80bb114494666','0a12675c0ef05d6a2e407a09767f6757','b94076c931b1bd67f2607746c7181f75']"

   strings:
      $hex_string = { 7661e2d05f72b4ac291397473a0e99aee7bf50a8c514c93093276ac1f779da1cad58cd48b6b717326b2f64fe0f0a6de567464c21ac05081da3867c4bd1334fcb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
