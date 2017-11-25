
rule m3e7_210c96cb656cc2c3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.210c96cb656cc2c3"
     cluster="m3e7.210c96cb656cc2c3"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['52e43ff79ff9f8b9d6e5c7eb845f7e96','ab9d8b1bf4f4debb4d39dcce08cf4ea0','c67cf37d99d6116d44f3c6bd5509ffc5']"

   strings:
      $hex_string = { 70e58d414da86cd51fee5718b788db136bb58c30d6464b80657495e44475ab319e2af3b051724cc93aac6940b2c34af19366995c075e7610e11e977327da6747 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
