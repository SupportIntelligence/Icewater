
rule k3f4_2534d156ca3b1110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.2534d156ca3b1110"
     cluster="k3f4.2534d156ca3b1110"
     cluster_size="70"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor bladabi"
     md5_hashes="['0051f98995575ecfc48709febe375648','047393665a43f2dbaecac4c3044357f8','2bf22d077a1c41a9e672a9dc64d4d366']"

   strings:
      $hex_string = { de0a2801f901bc034101d900eb0ac0043901990bf00439019e0bf304e100aa0bf904c900b10b4101d100910c1d050102a40ca2040902f00013001102e20c3005 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
