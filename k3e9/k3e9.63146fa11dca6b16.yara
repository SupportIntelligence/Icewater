
rule k3e9_63146fa11dca6b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fa11dca6b16"
     cluster="k3e9.63146fa11dca6b16"
     cluster_size="147"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['0d5d5538219c98ef8fb17d59da0c54a0','145846092700f6d71e488d08e2b2614b','6b4751e7fac5cfbfc33e0ebcd75549c0']"

   strings:
      $hex_string = { 0077007300280054004d00290020004f007000650072006100740069006e0067002000530079007300740065006d0000003e000d000100500072006f00640075 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
