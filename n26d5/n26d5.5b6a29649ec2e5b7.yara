
rule n26d5_5b6a29649ec2e5b7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5b6a29649ec2e5b7"
     cluster="n26d5.5b6a29649ec2e5b7"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['a6bcffc21083a00247b9f314b5060912194f6ce5','4c9f340625e927cbefd06b66f3838dfbc55a99d3','c32633e2dae55be5096fb9186b2624dcf62903ac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5b6a29649ec2e5b7"

   strings:
      $hex_string = { 7c9fb1c91946c7c6585bba4dadb6cbf31ff838f55a8d9b37aed2edb42957ca04cd1631111b7b75a377a763823024922ae1400862a1b326a456bf4fd191742268 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
