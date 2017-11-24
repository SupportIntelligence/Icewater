
rule m2321_09ba9246df0b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.09ba9246df0b4912"
     cluster="m2321.09ba9246df0b4912"
     cluster_size="35"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['018997bc341c32534f03b1755d5945fb','09c5f99bc5b34c9dde58e26f9b0a4700','540506cec49c8c6ef70f125cc7332f91']"

   strings:
      $hex_string = { 86b33fa5961269caa297c9686c88f47460172d096af3b7358dda1ae29b6fb67b08570b755190a032130e1884eff8d4d926de168a83617952d60c343620667380 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
