
rule k2321_09684922d9bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09684922d9bb1912"
     cluster="k2321.09684922d9bb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['3dd65c829c701056b8c96384b48ada00','81ffd986a8c94d8e684565f2fb2d9807','c4e0e87f7a91c7f743f2205f1670367d']"

   strings:
      $hex_string = { 5a2ef8bd7f321c761084c4fbfdabb5314d4be79f8f88cdd4c790dfbe9ed2f90d23f2f4611235af137d6508f600667ae329e0946ea080b61ae640a7a553a19e07 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
