
rule o26c9_45b4e44980000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c9.45b4e44980000932"
     cluster="o26c9.45b4e44980000932"
     cluster_size="401"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer malicious autoit"
     md5_hashes="['f0652f719ab1acff5aa919cc4d323f8dae935f0c','991eaf2ad27282707031db29a1661c2d947bec13','2bd38f0d2dac27132c0871325c18186b9340a73c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c9.45b4e44980000932"

   strings:
      $hex_string = { 895908443bd972454181fb00010000730485ff7438418bc3488d1d8a2bfaff99f7f94863c84863c2440fb68419c07b0c0049c1e0074c03c0420fb78443c0b00b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
