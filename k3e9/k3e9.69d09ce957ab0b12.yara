
rule k3e9_69d09ce957ab0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce957ab0b12"
     cluster="k3e9.69d09ce957ab0b12"
     cluster_size="124"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch riskware toolbar"
     md5_hashes="['03172d9b1199f2f0f8a59d2f1e964948','074b11beadd6434c46c2d22802e775b6','2c301d610d119588ee86090392bf5ed4']"

   strings:
      $hex_string = { a617c57bef19026b7a843a83d72774e8c3bf8280440ef5ef98d0ae0dc95bc70b4e13e734a9473ee68e93400f994946fa859e8c289b954400cc4ca415a1fef6ea }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
