
rule m3e9_13b96b552b4d6b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b96b552b4d6b16"
     cluster="m3e9.13b96b552b4d6b16"
     cluster_size="35"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy gepys shipup"
     md5_hashes="['0ba829997958d3da8fca1367b0f82de3','1d37c46cebb2ba6e9dc654449f011112','a726a4550e8d3aa193e3198bc339cff7']"

   strings:
      $hex_string = { f209006226be431b6f7e82855bd3667d9a48c775e35aee6dc544fc65a76bf95db36df655aa6cf74d4251f4459366f33da259ef353f66ea2d3047c1250d61b21d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
