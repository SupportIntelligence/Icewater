
rule o2321_113012ccea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.113012ccea210932"
     cluster="o2321.113012ccea210932"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr riskware"
     md5_hashes="['00e34044eb185f05bdbeab7ea0cbdcbf','0a4a086d7114cc81b335e80f454b2c2c','ff003bac8b43615d16cc56089f74d34b']"

   strings:
      $hex_string = { 03b21833ba1aefbeb82fc0c13b240e5d5e580214448b2905a9dbb5e28090d0e3f2f7b41fd91b3400bd5cd312361e92672bfa4bdc73fb8d3f9b59663856834c42 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
